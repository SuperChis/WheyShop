package com.sda.miniemag.service;

import com.sda.miniemag.model.ConfirmationToken;
import com.sda.miniemag.repository.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.text.MessageFormat;
import java.util.Optional;

@Service
@AllArgsConstructor
public class UserService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ConfirmationTokenService confirmationTokenService;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private EmailSenderService emailSenderService;


    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        final Optional<com.sda.miniemag.model.User> optionalUser = userRepository.findByEmail(email);
        com.sda.miniemag.model.User user = optionalUser.get();
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), user.getAuthorities());

    }

    public int signUpUser(com.sda.miniemag.model.User user) {
        if (user.getPassword().length() < 6) {
            return 2;
        }

        final String encryptedPassword = bCryptPasswordEncoder.encode(user.getPassword());

        user.setPassword(encryptedPassword);

        Optional<com.sda.miniemag.model.User> existingUser = userRepository.findByEmail(user.getEmail());
        if (!existingUser.isPresent()) {
            final com.sda.miniemag.model.User createdUser = userRepository.save(user);

            final ConfirmationToken confirmationToken = new ConfirmationToken(user);

            confirmationTokenService.saveConfirmationToken(confirmationToken);

//            sendConfirmationMail(createdUser.getEmail(), confirmationToken.getConfirmationToken());
            return 0;
        }
        return 1;

    }

//    public void sendConfirmationMail(String userMail, String token) {
//
//        final SimpleMailMessage mailMessage = new SimpleMailMessage();
//        mailMessage.setTo(userMail);
//        mailMessage.setSubject("Mail Confirmation Link!");
//        mailMessage.setFrom("noreply@miniemag.ro");
//        mailMessage.setText(
//                "Thank you for registering. Please click on the below link to activate your account." + "http://localhost:8080/sign-up/confirm?token="
//                        + token);
//
//        emailSenderService.sendEmail(mailMessage);
//    }

    public void confirmUser(ConfirmationToken confirmationToken) {

        final com.sda.miniemag.model.User user = confirmationToken.getUser();

        user.setEnabled(true);

        userRepository.save(user);

        confirmationTokenService.deleteConfirmationToken(confirmationToken.getId());

    }

    public com.sda.miniemag.model.User returnCurrentUser() {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof UserDetails) {
            String email = ((User) principal).getUsername();
            Optional<com.sda.miniemag.model.User> user = userRepository.findByEmail(email);
            return user.isPresent() ? user.get() : null;
        }
        return null;

    }
}
