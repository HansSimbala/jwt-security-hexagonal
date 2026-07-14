# Instrucciones del Proyecto

## Arquitectura
Este proyecto usa arquitectura hexagonal con los paquetes:
- `application/` → casos de uso (use cases)
- `domain/` → entidades, puertos e interfaces
- `infrastructure/` → adaptadores, controladores, repositorios

## Stack
- Java 21 + Spring Boot 3
- Spring Security + JWT
- Lombok para reducir boilerplate
- Maven como gestor de dependencias

## Reglas
- Respetar la separación de capas hexagonal
- No mezclar lógica de negocio con infraestructura
- Usar Lombok (@Data, @Builder, @RequiredArgsConstructor)
- Seguir principios SOLID
