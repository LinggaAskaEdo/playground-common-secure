package otis.playground.common.secure.annotation;

import otis.playground.common.secure.model.enumeration.EGroup;
import otis.playground.common.secure.model.enumeration.EPermission;
import otis.playground.common.secure.model.enumeration.ERole;

import java.lang.annotation.*;

@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Secured {
    EGroup[] groups();
    ERole[] roles();
    EPermission[] permissions();
}
