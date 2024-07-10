from structlog.stdlib import get_logger
from vyper import v

from competition_api.config import init_vyper
from competition_api.tasks.gp import check_gp
from competition_api.tasks.pool import build_redis_settings
from competition_api.tasks.vds import check_vds

LOGGER = get_logger(__name__)

init_vyper()

v.set_default("worker.health_check_interval", 30)
v.set_default("worker.max_concurrent_jobs", 50)


class Worker:
    health_check_interval = v.get_int("worker.health_check_interval")
    max_jobs = v.get_int("worker.max_concurrent_jobs")
    keep_result_forever = True

    job_timeout = 1000

    functions = [check_vds, check_gp]

    redis_settings = build_redis_settings()
