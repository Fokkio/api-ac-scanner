class OrderController {
  Object getOrder(Long id, User user) {
    return orderRepository.findByIdAndOwnerId(id, user.id());
  }

  @PreAuthorize("hasRole('ADMIN')")
  @DeleteMapping("/staff/users/{id}")
  void deleteUser(Long id) {
    userService.delete(id);
  }
}
