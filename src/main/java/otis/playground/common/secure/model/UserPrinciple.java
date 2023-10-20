package otis.playground.common.secure.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class UserPrinciple {
    private String id;
    private String username;
    private UserGroup group;
}
