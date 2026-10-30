from __future__ import annotations

import argparse
import html
import json
import mimetypes
import sqlite3
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .core import connect, initialize, scan_projects
from .context_graph import ProjectGraph


ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"


def decode_rows(rows: list[sqlite3.Row], json_fields: tuple[str, ...] = ()) -> list[dict]:
    output = []
    for row in rows:
        item = dict(row)
        for field in json_fields:
            if field in item:
                try: item[field.removesuffix("_json")] = json.loads(item.pop(field) or "null")
                except json.JSONDecodeError: item[field.removesuffix("_json")] = None
        output.append(item)
    return output


class AnalyzerServer(ThreadingHTTPServer):
    def __init__(self, address, handler, db_path: Path, collection_root: Path):
        super().__init__(address, handler)
        self.db_path = db_path
        self.collection_root = collection_root

    def db(self) -> sqlite3.Connection:
        return connect(self.db_path)


class Handler(BaseHTTPRequestHandler):
    server: AnalyzerServer

    def log_message(self, fmt: str, *args) -> None:
        print(f"{self.address_string()} - {fmt % args}")

    def send_json(self, value, status=HTTPStatus.OK) -> None:
        data = json.dumps(value, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status); self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data))); self.send_header("Cache-Control", "no-store")
        self.end_headers(); self.wfile.write(data)

    def send_file(self, path: Path) -> None:
        if not path.is_file(): return self.send_error(HTTPStatus.NOT_FOUND)
        data = path.read_bytes(); content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK); self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data))); self.send_header("Cache-Control", "no-cache")
        self.end_headers(); self.wfile.write(data)

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/api/rescan": return self.send_error(HTTPStatus.NOT_FOUND)
        with self.server.db() as db:
            self.send_json({"projects": scan_projects(db, self.server.collection_root)})

    def do_GET(self) -> None:
        parsed = urlparse(self.path); path = parsed.path; query = parse_qs(parsed.query, keep_blank_values=True)
        if path == "/" or path == "/index.html": return self.send_file(STATIC / "index.html")
        if path.startswith("/static/"):
            name = unquote(path.removeprefix("/static/"))
            candidate = (STATIC / name).resolve()
            try: candidate.relative_to(STATIC.resolve())
            except ValueError: return self.send_error(HTTPStatus.FORBIDDEN)
            return self.send_file(candidate)
        if not path.startswith("/api/"): return self.send_error(HTTPStatus.NOT_FOUND)
        try:
            with self.server.db() as db: return self.handle_api(db, path, query)
        except (ValueError, sqlite3.DatabaseError) as exc:
            return self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def handle_api(self, db: sqlite3.Connection, path: str, query: dict[str, list[str]]) -> None:
        if path == "/api/projects":
            rows = db.execute("SELECT id,name,path,hostname,identity,schema_version,status,started_at,finished_at,indexed_at FROM projects ORDER BY name").fetchall()
            return self.send_json({"items": decode_rows(rows)})
        parts = path.strip("/").split("/")
        if len(parts) < 3 or parts[0] != "api" or parts[1] != "projects": return self.send_error(HTTPStatus.NOT_FOUND)
        pid = parts[2]
        project = db.execute("SELECT * FROM projects WHERE id=?", (pid,)).fetchone()
        if not project: return self.send_error(HTTPStatus.NOT_FOUND, "Unknown project")
        action = parts[3] if len(parts) > 3 else "overview"
        if action == "overview":
            source_counts = db.execute("SELECT status,COUNT(*) count FROM sources WHERE project_id=? GROUP BY status", (pid,)).fetchall()
            metrics = {
                "sources": db.execute("SELECT COUNT(*) FROM sources WHERE project_id=?", (pid,)).fetchone()[0],
                "records": db.execute("SELECT COUNT(*) FROM records WHERE project_id=?", (pid,)).fetchone()[0],
                "artifacts": db.execute("SELECT COUNT(*) FROM artifacts WHERE project_id=?", (pid,)).fetchone()[0],
                "findings": db.execute("SELECT COUNT(*) FROM findings WHERE project_id=?", (pid,)).fetchone()[0],
                "decoded_userassist": db.execute("SELECT COUNT(*) FROM decoded WHERE project_id=? AND decoder='userassist'", (pid,)).fetchone()[0],
                "decoded_browser": db.execute("SELECT COUNT(*) FROM decoded WHERE project_id=? AND decoder='browser'", (pid,)).fetchone()[0],
                "decoded_ad": db.execute("SELECT COUNT(*) FROM decoded WHERE project_id=? AND decoder='ad'", (pid,)).fetchone()[0],
                "decoded_services": db.execute("SELECT COUNT(*) FROM decoded WHERE project_id=? AND decoder='services'", (pid,)).fetchone()[0],
                "decoded_service_acl": db.execute("SELECT COUNT(*) FROM decoded WHERE project_id=? AND decoder='service_acl'", (pid,)).fetchone()[0],
                "decoded_file_acl": db.execute("SELECT COUNT(*) FROM decoded WHERE project_id=? AND decoder='file_acl'", (pid,)).fetchone()[0],
            }
            item = dict(project); item["metadata"] = json.loads(item.pop("metadata_json")); item["errors"] = json.loads(item.pop("errors_json"))
            return self.send_json({"project": item, "metrics": metrics, "source_statuses": decode_rows(source_counts)})
        if action == "sources":
            section = query.get("section", [None])[0]
            sql = "SELECT section,name,status,record_count,output_file,errors_json,summary_json FROM sources WHERE project_id=?"
            params: tuple = (pid,)
            if section: sql += " AND section=?"; params += (section,)
            rows = db.execute(sql + " ORDER BY section,name", params).fetchall()
            return self.send_json({"items": decode_rows(rows, ("errors_json", "summary_json"))})
        if action == "records":
            section = query.get("section", [""])[0]; source = query.get("source", [""])[0]
            limit = min(max(int(query.get("limit", ["100"])[0]), 1), 1000); offset = max(int(query.get("offset", ["0"])[0]), 0)
            rows = db.execute("SELECT id,ordinal,data_json FROM records WHERE project_id=? AND section=? AND source=? ORDER BY ordinal LIMIT ? OFFSET ?", (pid, section, source, limit, offset)).fetchall()
            count = db.execute("SELECT COUNT(*) FROM records WHERE project_id=? AND section=? AND source=?", (pid, section, source)).fetchone()[0]
            return self.send_json({"items": [{"id":r["id"],"ordinal":r["ordinal"],"data":json.loads(r["data_json"])} for r in rows], "total": count, "limit": limit, "offset": offset})
        if action == "decoded":
            decoder = query.get("decoder", [""])[0]; kind = query.get("kind", [None])[0]
            rows = db.execute("SELECT id,source,data_json FROM decoded WHERE project_id=? AND decoder=? ORDER BY id", (pid, decoder)).fetchall()
            items = [{"id":r["id"],"source":r["source"],"data":json.loads(r["data_json"])} for r in rows]
            if kind: items = [x for x in items if x["data"].get("kind") == kind]
            return self.send_json({"items": items})
        if action == "findings":
            rows = db.execute("SELECT id,severity,title,summary,section,source,evidence_json FROM findings WHERE project_id=? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,id", (pid,)).fetchall()
            return self.send_json({"items": decode_rows(rows, ("evidence_json",))})
        if action == "evidence":
            decoded = "decoded_id" in query
            ident = int(query.get("decoded_id" if decoded else "record_id", ["0"])[0])
            table = "decoded" if decoded else "records"
            row = db.execute(f"SELECT source,data_json FROM {table} WHERE project_id=? AND id=?", (pid, ident)).fetchone()
            if not row: return self.send_error(HTTPStatus.NOT_FOUND)
            return self.send_json({"source": row["source"], "data": json.loads(row["data_json"])})
        if action == "graph":
            layers = query.get("layers", [None])[0]
            return self.send_json(ProjectGraph(db, pid).view(
                section=query.get("section", ["all"])[0],
                focus=query.get("focus", [None])[0],
                layers=layers.split(",") if layers else ([] if layers == "" else None),
                limit=int(query.get("limit", ["18"])[0]),
                offset=int(query.get("offset", ["0"])[0]),
                q=query.get("q", [""])[0],
            ))
        if action == "entity":
            graph = ProjectGraph(db, pid)
            node = graph.nodes.get(query.get("id", [""])[0])
            if not node:
                return self.send_error(HTTPStatus.NOT_FOUND)
            return self.send_json(node)
        if action == "artifacts":
            rows = db.execute("SELECT id,section,source,original_path,name,category,profile_sid,profile_path,length,sha256,local_path IS NOT NULL available FROM artifacts WHERE project_id=? ORDER BY section,source,original_path", (pid,)).fetchall()
            return self.send_json({"items": decode_rows(rows)})
        if action == "artifact" and len(parts) > 4:
            artifact = db.execute("SELECT * FROM artifacts WHERE project_id=? AND id=?", (pid, int(parts[4]))).fetchone()
            if not artifact or not artifact["local_path"]: return self.send_error(HTTPStatus.NOT_FOUND)
            file_path = Path(artifact["local_path"]).resolve(); project_root = Path(project["path"]).resolve()
            try: file_path.relative_to(project_root)
            except ValueError: return self.send_error(HTTPStatus.FORBIDDEN)
            raw = file_path.read_bytes()[:524288]
            encoding = "utf-8"; text = None
            for candidate in ("utf-8-sig", "utf-16", "cp1251", "latin-1"):
                try: text = raw.decode(candidate); encoding = candidate; break
                except UnicodeDecodeError: continue
            return self.send_json({"artifact": dict(artifact), "preview": text, "encoding": encoding, "preview_bytes": len(raw), "truncated": file_path.stat().st_size > len(raw)})
        if action == "search":
            term = query.get("q", [""])[0].strip()
            if not term: return self.send_json({"items": []})
            rows = db.execute("SELECT section,source,snippet(search_index,3,'<mark>','</mark>',' … ',18) snippet FROM search_index WHERE project_id=? AND search_index MATCH ? LIMIT 100", (pid, '"'+term.replace('"','""')+'"')).fetchall()
            items = []
            for row in rows:
                item = dict(row)
                item["snippet"] = html.escape(item["snippet"]).replace("&lt;mark&gt;", "<mark>").replace("&lt;/mark&gt;", "</mark>")
                items.append(item)
            return self.send_json({"items": items})
        return self.send_error(HTTPStatus.NOT_FOUND)


def main() -> None:
    parser = argparse.ArgumentParser(description="Portable collection web analyzer")
    parser.add_argument("--collections", type=Path, default=Path(__file__).resolve().parents[1] / "output" / "from_portable" / "new")
    parser.add_argument("--database", type=Path, default=ROOT / "state" / "analyzer.db")
    parser.add_argument("--host", default="127.0.0.1"); parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-initial-scan", action="store_true")
    args = parser.parse_args()
    with connect(args.database) as db:
        initialize(db)
        if not args.no_initial_scan:
            results = scan_projects(db, args.collections)
            for result in results: print(f"[{result['status']}] {result['name']}")
    server = AnalyzerServer((args.host, args.port), Handler, args.database, args.collections.resolve())
    print(f"Analyzer: http://{args.host}:{args.port}")
    print(f"Collections: {args.collections.resolve()}")
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()


if __name__ == "__main__": main()
