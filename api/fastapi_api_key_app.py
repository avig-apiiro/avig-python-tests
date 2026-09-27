from fastapi import Depends, FastAPI

from authentication.fastapi_api_key import require_api_key

app = FastAPI()


@app.get("/reports/{report_id}", dependencies=[Depends(require_api_key)])
def get_report(report_id: int):
    return {"report_id": report_id, "status": "ready"}
