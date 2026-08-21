const express = require("express");
const router = express.Router();

router.get("/orders/:id", requireUser, async (req, res) => {
  const order = await prisma.order.findFirst({ where: { id: req.params.id, ownerId: req.user.id } });
  if (!order) return res.sendStatus(404);
  res.json(order);
});

router.delete("/staff/users/:id", requireAdmin, deleteUser);
