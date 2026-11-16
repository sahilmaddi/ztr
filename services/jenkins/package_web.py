from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


source = Path("apps/web/dist/application-demo-web/browser")
if not source.is_dir():
    raise SystemExit(f"Angular build output was not found: {source}")

with ZipFile("ci-web-build.zip", "w", ZIP_DEFLATED) as archive:
    for path in source.rglob("*"):
        if path.is_file():
            archive.write(path, path.relative_to(source).as_posix())
