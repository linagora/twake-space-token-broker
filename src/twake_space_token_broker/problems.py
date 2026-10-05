"""RFC 9457 problem details, the one error format of the broker's API."""

from http import HTTPStatus

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


class Problem(Exception):
    def __init__(
        self,
        *,
        status: int,
        code: str,
        title: str,
        detail: str,
        extensions: dict[str, str] | None = None,
    ) -> None:
        super().__init__(detail)
        self.status = status
        self.code = code
        self.title = title
        self.detail = detail
        self.extensions = extensions or {}

    def response(self) -> JSONResponse:
        return JSONResponse(
            status_code=self.status,
            media_type="application/problem+json",
            content={
                "type": f"urn:twake:problem:{self.code}",
                "title": self.title,
                "status": self.status,
                "detail": self.detail,
                "code": self.code,
                **self.extensions,
            },
        )


def _http_error(error: StarletteHTTPException) -> Problem:
    """Routing errors, such as an unknown path, named after their HTTP status."""
    phrase = HTTPStatus(error.status_code).phrase
    return Problem(
        status=error.status_code,
        code=phrase.lower().replace(" ", "_"),
        title=phrase,
        detail=str(error.detail),
    )


def install(app: FastAPI) -> None:
    async def handle_problem(_: Request, problem: Exception) -> JSONResponse:
        assert isinstance(problem, Problem)
        return problem.response()

    async def handle_http_error(_: Request, error: Exception) -> JSONResponse:
        assert isinstance(error, StarletteHTTPException)
        return _http_error(error).response()

    app.add_exception_handler(Problem, handle_problem)
    app.add_exception_handler(StarletteHTTPException, handle_http_error)
