#!/usr/bin/env bash
# AUTHOR: gh0st@nemesis.sh
set -xe

root=$PWD
hooks=$(ls .hooks)

for f in $hooks; do
	git_hook_file="${root}/.hooks/${f}"
	git_hook_link="${root}/.git/hooks/${f}"
	if [[ ! -f "${git_hook_link}" ]]; then
		ln -s "${git_hook_file}"  "${git_hook_link}"
	fi
done

