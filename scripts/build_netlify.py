import os
import re
from pathlib import Path
from urllib.parse import urlsplit


def build_netlify_redirects(backend_url: str, output_dir: Path) -> Path:
    backend_url = backend_url.strip().rstrip("/")
    parsed_url = urlsplit(backend_url)

    if (
        parsed_url.scheme != "https"
        or not parsed_url.hostname
        or parsed_url.username
        or parsed_url.password
        or parsed_url.path
        or parsed_url.query
        or parsed_url.fragment
        or re.search(r"[\s\\]", backend_url)
    ):
        raise ValueError(
            "FLASK_BACKEND_URL must be an HTTPS origin, such as "
            "'https://your-app.example.com'."
        )

    if parsed_url.port is not None and not 1 <= parsed_url.port <= 65535:
        raise ValueError("FLASK_BACKEND_URL must use a valid port.")

    output_dir.mkdir(parents=True)
    redirects_file = output_dir / "_redirects"
    redirects_file.write_text(
        f"/* {backend_url}/:splat 200!\n",
        encoding="utf-8",
    )
    return redirects_file


def main() -> None:
    backend_url = os.environ.get("FLASK_BACKEND_URL", "")
    if not backend_url:
        raise SystemExit(
            "Set FLASK_BACKEND_URL in Netlify to the public HTTPS URL of the "
            "deployed Flask backend."
        )

    output_dir = Path(__file__).resolve().parent.parent / "netlify-dist"
    try:
        build_netlify_redirects(backend_url, output_dir)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
