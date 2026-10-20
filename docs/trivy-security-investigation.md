# Investigación y reducción de superficie de ataque con Trivy

## Contexto

Durante el análisis de seguridad de la imagen Docker de la aplicación con Trivy se detectaron cuatro hallazgos de severidad HIGH asociados a paquetes que aparecían en el SBOM de Python/pip.

El objetivo fue determinar si esos componentes eran necesarios para ejecutar la aplicación y comprobar el resultado después del cambio.

## Hallazgos iniciales

Los cuatro hallazgos identificados fueron:

- `msgpack`: versión detectada 1.1.2; versión corregida indicada por Trivy: 1.2.1. Referencia: GHSA-6v7p-g79w-8964.
- `setuptools`: versión detectada 70.3.0; versión corregida indicada: 78.1.1. Referencia: CVE-2025-47273.
- `urllib3`: versión detectada 2.7.0; versión corregida indicada: 2.8.0. Referencias: CVE-2026-97687 y CVE-2026-97689.

Los resultados iniciales también mostraban una advertencia de Trivy sobre la posible imprecisión de los SBOM de terceros.

## Investigación

Se inspeccionó el SBOM incluido en la instalación de pip y se comprobaron las versiones detectadas.

La investigación permitió observar que:

- Algunos componentes figuraban como dependencias integradas o vendorizadas dentro de pip.
- La aplicación no utiliza pip para ejecutarse.
- El código de la aplicación utiliza módulos de la biblioteca estándar de Python.
- El proyecto no necesita instalar dependencias Python externas para ejecutar esta aplicación.

Por ese motivo, se decidió retirar pip de la imagen final de ejecución, en lugar de limitarse a ocultar los hallazgos del escaneo.

## Cambio implementado

En `app/Dockerfile` se eliminó pip y su metadata de la imagen final:

```dockerfile
RUN rm -rf \
    /usr/local/lib/python3.13/site-packages/pip \
    /usr/local/lib/python3.13/site-packages/pip-*.dist-info
```

La imagen mantiene Python y la aplicación. El contenedor ejecuta `app.py` directamente.

Esta decisión es adecuada para la imagen de ejecución actual porque la aplicación no necesita pip en tiempo de ejecución. Si en el futuro se agregan dependencias externas, deberán instalarse durante la construcción de la imagen y probarse antes de eliminar o modificar esta medida.

## Validaciones automatizadas

El workflow `.github/workflows/app-image-test.yml` ejecuta las siguientes comprobaciones:

1. Construcción de la imagen Docker.
2. Verificación de la versión de Python y de la presencia del archivo `/app/app.py`.
3. Comprobación de que pip no está disponible en la imagen final.
4. Prueba HTTP de la aplicación y validación de contenido de la respuesta.
5. Escaneo de la imagen con Trivy para severidades CRITICAL y HIGH.

## Resultados observados

En la ejecución validada de GitHub Actions:

- La imagen se construyó correctamente.
- Python informó la versión 3.13.16.
- `pip available: False`.
- `Application file exists: True`.
- La prueba HTTP finalizó con `HTTP response test passed`.
- Trivy identificó Debian 13.7 y reportó cero vulnerabilidades para el objetivo Debian analizado.
- El análisis reportó cero archivos específicos de lenguajes para analizar.
- La advertencia sobre SBOM de terceros continuó apareciendo.

## Alcance y limitaciones

El resultado de cero vulnerabilidades corresponde al objetivo Debian reportado por esta ejecución de Trivy. No demuestra que la imagen esté libre de cualquier vulnerabilidad.

La advertencia sobre SBOM de terceros debe tenerse en cuenta al interpretar los resultados. Además, el análisis no encontró archivos específicos de lenguajes, por lo que no corresponde afirmar que se realizó un análisis completo de dependencias Python de la aplicación.

El workflow actual utiliza `ignore-unfixed: true` y `exit-code: "0"`. Por lo tanto, el éxito del workflow por sí solo no debe interpretarse como una garantía de ausencia de vulnerabilidades.

## Estado del cambio

Los cambios se encuentran en la rama `test-trivy`. La validación de construcción, ejecución HTTP y escaneo descrita arriba se completó correctamente.

La integración a `main` debe realizarse después de revisar y aprobar el cambio y su documentación.
