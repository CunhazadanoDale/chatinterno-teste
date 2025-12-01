package com.athena.chat.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class GroupUpdateDTO {

    @NotBlank(message = "O nome do grupo é obrigatório")
    private String nome;

    private String descricao;
}
