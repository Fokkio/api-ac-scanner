from flask import Flask, request
from models import Order, User

app = Flask(__name__)

# VULNERABLE: BOLA — id from request reaches lookup with no owner check
@app.route("/api/orders", methods=["GET"])
def list_orders():
    oid = request.args.get("id")
    return Order.query.filter_by(id=oid).first()

# VULNERABLE: BFLA — admin-only delete with no role check
@app.route("/api/admin/orders/<int:oid>", methods=["DELETE"])
def admin_delete(oid):
    return Order.query.filter_by(id=oid).delete()

# VULNERABLE: Mass Assignment — raw json into model create
@app.route("/api/orders", methods=["POST"])
def create_order():
    return Order.create(**request.get_json())

# SAFE: rate-limited login (should NOT trigger API4)
@app.route("/api/login", methods=["POST"])
@limiter.limit("5/minute")
def login():
    return User.authenticate(request.json)

# SAFE: admin delete with role check (should NOT trigger BFLA)
@app.route("/api/admin/users/<int:uid>", methods=["DELETE"])
def safe_delete(uid):
    if not current_user.is_admin:
        abort(403)
    return User.query.filter_by(id=uid).delete()
