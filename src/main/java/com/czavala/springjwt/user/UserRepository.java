package com.czavala.springjwt.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {

    // obtiene user desde DB
    Optional<User> findUserByUsername(String username);
}
