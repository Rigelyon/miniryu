import os
from functools import wraps

import requests
from flask import Blueprint, Response, jsonify, redirect, render_template, request, session, url_for


web_bp = Blueprint("web", __name__)

RYU_API_URL = os.environ.get("RYU_API_URL", "http://127.0.0.1:8080/api")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("web.login"))
        return view_func(*args, **kwargs)

    return wrapped


def _proxy_get(path: str):
    response = requests.get(f"{RYU_API_URL}{path}", timeout=3)
    response.raise_for_status()
    return response.json()


def _proxy_post(path: str, payload=None):
    response = requests.post(f"{RYU_API_URL}{path}", json=payload or {}, timeout=3)
    response.raise_for_status()
    return response.json() if response.content else {"status": "ok"}


@web_bp.route("/")
def index():
    return redirect(url_for("web.dashboard"))


@web_bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["logged_in"] = True
            return redirect(url_for("web.dashboard"))
        error = "Invalid username or password"
    return render_template("login.html", error=error)


@web_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("web.login"))


@web_bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@web_bp.route("/network/status", methods=["GET"])
@login_required
def network_status():
    try:
        data = _proxy_get("/status")
        return jsonify(data)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 502


@web_bp.route("/attacks", methods=["GET"])
@login_required
def attacks():
    try:
        data = _proxy_get("/attacks")
        return jsonify(data)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 502


@web_bp.route("/block_ip", methods=["POST"])
@login_required
def block_ip():
    payload = request.get_json(silent=True) or {}
    ip = payload.get("ip")
    duration = int(payload.get("duration", 120))
    if not ip:
        return jsonify({"error": "missing ip"}), 400

    try:
        data = _proxy_post("/block_ip", {"ip": ip, "duration": duration})
        return jsonify(data)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 502


@web_bp.route("/enable_load_balancer", methods=["POST"])
@login_required
def enable_load_balancer():
    try:
        data = _proxy_post("/load_balancer/enable")
        return jsonify(data)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 502


@web_bp.route("/disable_load_balancer", methods=["POST"])
@login_required
def disable_load_balancer():
    try:
        data = _proxy_post("/load_balancer/disable")
        return jsonify(data)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 502


@web_bp.route("/health", methods=["GET"])
def health():
    return Response("ok", mimetype="text/plain")
