# Build Path Policies

Apply only the section matching `blueprint.build_plan.build_path`. The generic
policy applies only when no named section matches.

## official_image_direct

Use `blueprint.build_plan.selected_image` directly in `docker-compose.yml`.
Do not generate a Dockerfile or perform build-time resource checks.

## official_image_extended

Generate a Dockerfile whose `FROM` is exactly
`blueprint.build_plan.selected_image`. Package-version checking is unnecessary
unless the Dockerfile installs a separate selected system or language package.
Use planner-provided resource facts or template notes for packages added by the
generated Dockerfile; if required package availability is absent, document the
gap instead of inventing a repository.
Use `blueprint.build_plan.build_resources.base_images` for any planner-selected
runtime, builder, or helper image.
If an additional builder or helper stage is needed, choose a currently
maintained base image unless the blueprint or tool observations explicitly
require an obsolete distribution. Do not add archive or snapshot package sources
for builder/helper stages merely because the affected component version is old.

## system_package_repo

Use the blueprint-selected package name and version. If planner-provided
package/resource facts are available in
`blueprint.build_plan.build_resources.package_versions`,
`blueprint.build_plan.build_resources.version_resolution.selected_candidate`,
`blueprint.build_plan.build_resources.package_dependencies`, or
`artifact_probe_results`, follow them.

For historical Debian/Ubuntu versions, use a tool-provided snapshot source when
available in the blueprint. If no verified source is available, document the
unresolved source instead of inventing a snapshot URL or timestamp.

## custom_package_repo

Use only the custom repository supplied by the blueprint. Apply
`template_requirements.notes` as mandatory implementation constraints for this
path. If those notes name concrete database packages, signing keys, keyservers,
base-image preferences, or runtime fixes, use those exact instructions with
`blueprint.build_plan.selected_version`.

Database packages from the custom repository do not need base-image package
repository verification in the generator, even when their package names come
from `template_requirements.notes`.

Use planner-provided resource facts for packages installed from the base image's
repositories. Do not invent repository, mirror, direct-package, or signing-key
URLs beyond values supplied by `build_plan`, `build_plan.build_resources`,
`template_requirements.notes`, `artifact_probe_results`, or `verified_artifacts`. If dependencies are
unavailable, remove unnecessary dependencies or document the unresolved package.

When a dependency/resource observation reports archived default sources and provides
`replacement_source_list` with `apt_update_options`, use those exact values
before installing base-image dependencies. Do not keep the archived image's
obsolete default sources active.

README must state that custom-repository database package/version availability
was not verified.

## language_package_repo

Use the selected package and version with the package ecosystem and package
facts supplied by the blueprint. Do not add an unverified package source.

## prebuilt_binary

The selected artifact is not a base-image system package. Use only
`blueprint.build_plan.selected_download_url`,
`blueprint.build_plan.build_resources.urls`, or a verified artifact. Do not
invent an artifact URL.

## source_compile

Use planner-provided build resources, package dependency facts, URL facts, or
template notes for dependencies needed to fetch, unpack, configure, compile,
link, install, and run the source. Use
`blueprint.build_plan.selected_download_url`; when it is empty, document the
unresolved source rather than inventing a URL.
Use a maintained base image first. Use an archived/EOL base image only after
planner observations show maintained candidates cannot provide the required
build and runtime dependencies.

## generic

Follow `blueprint.build_plan` and planner observations. Do not invent package
sources or remote URLs.
