<?php
$order = Order::where('owner_id', $request->user()->id)->findOrFail($request->route('id'));
Route::delete('/staff/users/{id}', $deleteUser)->middleware('role:admin');
