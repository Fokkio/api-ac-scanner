class OrderController {
  Object getOrder(Long id) {
    return orderRepository.findById(id);
  }

  @DeleteMapping("/admin/users/{id}")
  void deleteUser(Long id) {
    userService.delete(id);
  }

  void updateProfile(User user, UpdateRequest request) {
    user.setRole(request.getRole());
  }
}
