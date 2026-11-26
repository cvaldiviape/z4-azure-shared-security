# z4-shared-security

Librería que configura cada servicio Z4 como *resource server*: valida en cada petición el JWT que emite auth-service, traduce el claim `roles` a roles de Spring Security y aplica CORS. No es un servicio: no arranca, no tiene puerto ni base de datos.

## Qué contiene

| #   | Clase                         | Qué hace                                          |
|-----|-------------------------------|---------------------------------------------------|
| 1   | `Z4JwtProperties`             | Lee `app.jwt.secret`                              |
| 2   | `Z4SecurityProperties`        | Lee las reglas de acceso de `app.security.*`      |
| 3   | `JwtRolesConverter`           | Claim `roles: ["ADMIN"]` → autoridad `ROLE_ADMIN` |
| 4   | `Z4SecurityAutoConfiguration` | Crea el `JwtDecoder` y la cadena de seguridad     |

## Configuración en el servicio

```yaml
app:
  jwt:
    secret: ${JWT_SECRET:change-me-change-me-change-me-32-bytes}
  security:
    public-paths: /actuator/health          # sin token
    admin-paths: /ops/**                    # token con rol ADMIN
    cors-allowed-origins: http://localhost:4200
```

| #   | Propiedad                           | Por defecto        | Significado                           |
|-----|-------------------------------------|--------------------|---------------------------------------|
| 1   | `app.jwt.secret`                    | (obligatoria)      | Clave HS256, la misma de auth-service |
| 2   | `app.security.public-paths`         | `/actuator/health` | Rutas que no piden token              |
| 3   | `app.security.admin-paths`          | vacío              | Rutas que exigen el rol admin         |
| 4   | `app.security.admin-role`           | `ADMIN`            | Nombre del rol admin                  |
| 5   | `app.security.cors-allowed-origins` | vacío              | Orígenes del navegador permitidos     |

Cualquier otra ruta exige un JWT válido. Si el servicio define su propio `SecurityFilterChain` o `JwtDecoder`, la librería usa el del servicio.

## Instalar en local

Las librerías se compilan con Java 21. Si tu terminal usa otra versión (revisa con `java -version`), cámbiala primero:

```bash
export JAVA_HOME=$(/usr/libexec/java_home -v 21)
```

Después instala:

```bash
./mvnw install
```

Si te olvidas del `export`, Maven falla con `class file version 65.0 ... only recognizes class file versions up to 61.0`: 65 es Java 21 y 61 es Java 17.

## Usar en un servicio

```xml
<dependency>
    <groupId>com.z4greed</groupId>
    <artifactId>z4-shared-security</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

La librería ya trae `spring-boot-starter-security` y `spring-boot-starter-oauth2-resource-server`.
