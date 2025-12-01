package com.athena.chat.dto;


import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class GroupCreateDTO {

    @NotBlank(message = "O nome do grupo é obrigatório")
    private String nome;

    private String descricao;

    @NotNull(message = "A lista de usuários é obrigatória")
    private List<Long> usuariosIds;
}
