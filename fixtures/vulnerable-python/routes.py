@app.get("/orders/{order_id}")
def get_order(request):
    return db.query(Order).get(request.path_params["order_id"])


@app.delete("/admin/users/{user_id}")
def delete_user(user_id: int):
    return service.delete_user(user_id)


user.role = request.json["role"]
