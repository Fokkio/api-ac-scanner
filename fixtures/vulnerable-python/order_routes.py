from flask import Flask, request
from models import Order

app = Flask(__name__)

# VULNERABLE: BOLA — id from path, no ownership check
@app.route("/api/orders/<int:oid>")
def get_order(oid):
    o = Order.query.filter_by(id=oid).first()
    return {"data": o.to_dict()}
