package otis.playground.common.secure.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

import java.util.Objects;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
public class UserRolePermission {
    private String name;
    private Set<String> permissions;

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;

        if (!(o instanceof UserRolePermission that))
            return false;

        return Objects.equals(name, that.name) && Objects.equals(permissions, that.permissions);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, permissions);
    }
}
