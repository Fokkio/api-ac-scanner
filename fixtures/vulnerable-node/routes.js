const express = require("express");
const router = express.Router();

router.get("/api/orders/:id", async (req, res) => {
  const order = await prisma.order.findUnique({ where: { id: req.params.id } });
  res.json(order);
});

router.delete("/admin/users/:id", deleteUser);

user.role = req.body.role;
