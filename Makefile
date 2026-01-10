.PHONY: release help

help:
	@echo "Available targets:"
	@echo "  release [VERSION=x.y.z]    - Release synapse: bump version, commit, tag vx.y.z, and push"
	@echo "                              If VERSION is not provided, automatically bumps patch version from latest tag"
	@echo "  help                       - Show this help message"

release:
	@if [ -z "$(VERSION)" ]; then \
		LATEST_TAG=$$(git tag --sort=-version:refname | head -1); \
		if [ -z "$$LATEST_TAG" ]; then \
			echo "Error: No tags found. Please specify VERSION=x.y.z"; \
			exit 1; \
		fi; \
		LATEST_VERSION=$$(echo $$LATEST_TAG | sed 's/^v//'); \
		VERSION=$$(echo $$LATEST_VERSION | awk -F. '{$$NF = $$NF + 1; print $$1"."$$2"."$$3}'); \
		echo "No VERSION specified. Bumping latest tag $$LATEST_TAG to $$VERSION"; \
	else \
		VERSION=$(VERSION); \
	fi; \
	echo "Releasing synapse version $$VERSION..."; \
	sed -i.bak "s/^VERSION=.*$$/VERSION=$$VERSION/" install.sh && rm install.sh.bak; \
	sed -i.bak "s/^version = \".*\"/version = \"$$VERSION\"/" Cargo.toml && rm Cargo.toml.bak; \
	sed -i.bak "s/synapse_version: \".*\"/synapse_version: \"$$VERSION\"/" ansible/playbook.yml && rm ansible/playbook.yml.bak; \
	sed -i.bak "s/synapse_version: \".*\"/synapse_version: \"$$VERSION\"/" ansible/group_vars/all_example.yml && rm ansible/group_vars/all_example.yml.bak; \
	sed -i.bak "s/synapse_version: \".*\"/synapse_version: \"$$VERSION\"/" ansible/roles/synapse/defaults/main.yml && rm ansible/roles/synapse/defaults/main.yml.bak; \
	cargo update -p synapse; \
	DATE=$$(date -R); \
	CHANGELOG_ENTRY="synapse ($$VERSION-1) stable; urgency=medium\n\n  * Release synapse $$VERSION\n  * More info: https://github.com/gen0sec/synapse/releases\n\n -- Gen0Sec <support@gen0sec.com>  $$DATE"; \
	printf "$$CHANGELOG_ENTRY\n\n" | cat - pkg/deb/debian/changelog > pkg/deb/debian/changelog.tmp && mv pkg/deb/debian/changelog.tmp pkg/deb/debian/changelog; \
	RPM_DATE=$$(date "+%a %b %d %Y"); \
	RPM_CHANGELOG_ENTRY="* $$RPM_DATE Gen0Sec <support@gen0sec.com> - $$VERSION-1\n- Release synapse $$VERSION\n- More info: https://github.com/gen0sec/synapse/releases"; \
	awk -v entry="$$RPM_CHANGELOG_ENTRY" '/^%changelog$$/ {print; print ""; print entry; next} {print}' pkg/rpm/synapse.spec > pkg/rpm/synapse.spec.tmp && mv pkg/rpm/synapse.spec.tmp pkg/rpm/synapse.spec; \
	git add Cargo.toml Cargo.lock install.sh ansible/playbook.yml ansible/group_vars/all_example.yml ansible/roles/synapse/defaults/main.yml pkg/deb/debian/changelog pkg/rpm/synapse.spec; \
	git commit -m "chore: release synapse $$VERSION"; \
	git tag v$$VERSION; \
	git push origin main; \
	git push origin tag v$$VERSION; \
	echo "Synapse version $$VERSION released successfully!"
