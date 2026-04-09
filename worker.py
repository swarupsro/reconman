from redis import Redis
from rq import Connection, Worker

from app import create_app


app = create_app(initialize_database=False)


def main() -> None:
    with app.app_context():
        redis_connection = Redis.from_url(app.config["RQ_REDIS_URL"])
        with Connection(redis_connection):
            worker = Worker(["scans"])
            worker.work()


if __name__ == "__main__":
    main()
