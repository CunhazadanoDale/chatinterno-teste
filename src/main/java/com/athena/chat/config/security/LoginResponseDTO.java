package com.athena.chat.config.security;

import com.athena.chat.dto.simpledto.UserSimpleDTO;

public record LoginResponseDTO (UserSimpleDTO userDTO, String cookie) {}
