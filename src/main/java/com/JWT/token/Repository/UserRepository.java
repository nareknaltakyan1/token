package com.JWT.token.Repository;

import com.JWT.token.entity.User;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends CrudRepository<User, Integer> {
	User findByUsername(String username);
}