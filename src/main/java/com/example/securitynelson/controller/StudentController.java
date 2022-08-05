package com.example.securitynelson.controller;


import com.example.securitynelson.student.Student;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "Anna Smith"),
            new Student(2, "Linda Parrot"),
            new Student(3, "Tom Bill")
    );

    @GetMapping(path = "{studentId}")
//    @PreAuthorize("hasAnyRole('ROLE_STUDENT')")
    public Student getStudent(@PathVariable("studentId") Integer studentId) {

        System.out.println("get students from student controller");
        return STUDENTS.stream()
                .filter(student -> studentId.equals(student.getStudentId()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("student " + studentId + "does not exist"));
    }
}
