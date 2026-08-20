const express = require("express");
const app = express();
app.use(express.json());

// VULNERABLE: BOLA — user-controlled id reaches a lookup with no owner check
app.get("/api/users/:id", (req, res) => {
  const user = User.findById(req.params.id); // no ownership verification
  res.json(user);
});

// VULNERABLE: Mass Assignment — raw body to create
app.post("/api/users", (req, res) => {
  const u = User.create(req.body); // role/isAdmin client-controllable
  res.json(u);
});

// SAFE: owner-scoped query
app.get("/api/orders/:id", (req, res) => {
  const o = Order.findOne({ _id: req.params.id, owner: req.user.id });
  if (!o) return res.status(404).json({ error: "not found" });
  res.json(o);
});

function User() {}
function Order() {}

app.listen(3000);
