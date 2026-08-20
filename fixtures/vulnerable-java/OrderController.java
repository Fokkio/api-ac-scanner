import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;

@RestController
@RequestMapping("/api")
public class OrderController {

    @Autowired
    private OrderRepository orderRepository;

    // VULNERABLE: BOLA — path variable reaches repo lookup with no owner check
    @GetMapping("/orders/{id}")
    public Order getOrder(@PathVariable("id") String id) {
        return orderRepository.findById(id);  // missing ownership verification
    }

    // VULNERABLE: Mass Assignment — raw request body mapped straight to entity
    @PostMapping("/orders")
    public Order createOrder(@RequestBody Order order) {
        return orderRepository.save(order);  // role/owner fields client-controllable
    }

    // SAFE: ownership check present
    @GetMapping("/profile")
    public User profile(@RequestParam("uid") String uid) {
        if (!securityService.authorize(getCurrentUser(), uid)) {
            throw new ForbiddenException();
        }
        return userRepository.findById(uid);
    }
}
