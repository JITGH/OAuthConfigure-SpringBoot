package service;


import enums.AuthProvider;

import model.User;
import repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserService {

    private final UserRepository usersRepository;
    private final PasswordEncoder passwordEncoder;

    public User registerUserLocal(User user){
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setAuthProvide(AuthProvider.LOCAL);
        return  usersRepository.save(user);
        

    }
    public User loginUserLocal(User user){
    	User existingUser=usersRepository.findByEmail(user.getEmail()).orElse(null);
    	if(existingUser!=null) {
    		if(!passwordEncoder.matches(user.getPassword(),existingUser.getPassword())) {
    			throw new RuntimeException("User Password Not Match");
    		}
    		return existingUser;
    	}
    	throw new RuntimeException("User Not Found");
    }
    
    
    public User loginRegisterByGoogleOAuth2(OAuth2AuthenticationToken auth2AuthenticationToken){
    	
    	
    	OAuth2User oAuth2User=auth2AuthenticationToken.getPrincipal();
    	String email=oAuth2User.getAttribute("email");
    	String name=oAuth2User.getAttribute("name");
    	
    	log.info("USER FROM GOOGLE EMAIL IS {}",email);
    	log.info("USER NAME FROM EMAIL IS {}",name);
    	
    	User user=usersRepository.findByEmail(email).orElse(null);
    	
    	if(user==null) {
    		user=new User();
    		user.setName(name);
    		user.setEmail(email);
    		user.setAuthProvide(AuthProvider.GOOGLE);
    		return usersRepository.save(user);
    	}
    	return user;
    }
    	
    
}
