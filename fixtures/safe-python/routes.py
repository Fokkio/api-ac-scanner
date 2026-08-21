@app.get("/orders/{order_id}", dependencies=[Depends(require_user)])
def get_order(order_id: int, user=Depends(require_user)):
    return db.query(Order).filter(Order.id == order_id, Order.owner_id == user.id).one_or_none()


@app.delete("/staff/users/{user_id}", dependencies=[Depends(require_admin)])
def delete_user(user_id: int):
    return service.delete_user(user_id)
