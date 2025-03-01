import multiprocessing
import os

name = "Gunicorn config for FastAPI"

bind = "0.0.0.0:8000"

worker_class = "uvicorn.workers.UvicornWorker"
workers = 1
timeout = 120
keepalive = 5
