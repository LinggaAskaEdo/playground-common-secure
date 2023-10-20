package otis.playground.common.secure.model;

import lombok.*;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class SecureResponse {
    private int status;
    private String message;
    private String description;
}
