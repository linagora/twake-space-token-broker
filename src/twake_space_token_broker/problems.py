"""RFC 9457 problem details, the one error format of the broker's API."""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


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


def install(app: FastAPI) -> None:
    async def handle_problem(_: Request, problem: Exception) -> JSONResponse:
        assert isinstance(problem, Problem)
        return problem.response()

    app.add_exception_handler(Problem, handle_problem)
