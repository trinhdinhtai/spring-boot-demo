package com.taitd.auth.dto;

import lombok.Builder;
import lombok.Data;
import java.util.List;

@Data
@Builder
public class UserDto {
    private String sub;
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private List<String> roles;
}
