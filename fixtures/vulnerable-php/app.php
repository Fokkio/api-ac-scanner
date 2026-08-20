<?php
// VULNERABLE: BOLA — id from GET, no ownership check
$id = $_GET['id'];
$order = Order::find($id);   // missing owner scoping
echo json_encode($order);

// VULNERABLE: Mass Assignment — raw request into fill()
$model->fill($_POST);  // role/isAdmin client-controllable
$model->save();
