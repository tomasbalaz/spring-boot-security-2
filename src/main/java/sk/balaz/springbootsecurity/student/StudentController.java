package sk.balaz.springbootsecurity.student;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {

    @GetMapping("{studentId}")
    public Student getStudent(@PathVariable("studentId") Integer id) {
        return new Student(1, "James Bond");
    }
}
