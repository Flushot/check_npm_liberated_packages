#!/usr/bin/env python
from __future__ import absolute_import, division, print_function, unicode_literals

import hashlib
import json
import os
import re
import sys
from pprint import pprint

import argparse
import deepdiff


def get_suspect_packages():
    """
    Package names suspected of possible hijacking.

    This list was obtained from:
    https://medium.com/@azerbike/i-ve-just-liberated-my-modules-9045c06be67c#.7kh6ics0w
    """
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'gistfile1.txt'), 'r') as f:
        return map(lambda line: line.strip(), f.readlines())


def parse_manifest(manifest_path):
    """
    Parses a package.json manifest file.
    """
    with open(manifest_path, 'r') as f:
        data = f.read()
        if data:
            return json.loads(data)
        else:
            return {}


def walk_path(start_path, match_pattern=None, recursive=True):
    """
    Recursively walk a directory, yielding everything path it visits.
    """
    if match_pattern is None:
        match_pattern = re.compile(r'.*')

    if os.path.isdir(start_path):
        for dir_entry in os.listdir(start_path):
            file_path = os.path.join(start_path, dir_entry)
            if os.path.isdir(file_path):
                if recursive:
                    for path in walk_path(file_path, match_pattern, recursive):
                        yield path
                else:
                    yield path
            elif match_pattern.search(file_path):
                yield file_path
    else:
        yield start_path


def build_tree(base_path, match_pattern, leaf_evaluator):
    """
    Build a directory tree represented as a dict.
    """
    if not os.path.exists(base_path):
        raise ValueError('path does not exist: '.format(base_path))

    tree = {}
    start_segment = len(base_path.split(os.path.sep))

    for path in walk_path(base_path, match_pattern):
        segments = path.split(os.path.sep)[start_segment:]
        segments_len = len(segments)

        subtree = tree
        for i, segment in enumerate(segments):
            if segment not in subtree:
                if i == segments_len - 1:
                    # File
                    subtree[segment] = leaf_evaluator(path)
                else:
                    # Directory
                    subtree[segment] = {}
            subtree = subtree[segment]

    return tree


def create_npm_leaf_evaluator(manifest_pattern):
    """
    Creates a leaf evaulator that parses package.json leaves and returns
    the manifest contents.
    """
    suspect_packages = set(get_suspect_packages())
    def leaf_evaluator(path):
        leaf = {}

        if manifest_pattern.search(path):
            manifest = parse_manifest(path)
            if manifest.get('name') in suspect_packages:
                leaf = manifest

        return leaf

    return leaf_evaluator


def build_npm_tree(path):
    manifest_pattern = re.compile(os.path.sep + r'package\.json$')
    return build_tree(path, manifest_pattern, create_npm_leaf_evaluator(manifest_pattern))


def main():
    argp = argparse.ArgumentParser(description='Ensures "liberated" node_modules are not compromised')
    argp.add_argument('baseline_path', help='Baseline (untainted) node_modules path')
    argp.add_argument('tainted_path', help='Tainted node_modules path to compare against baseline')
    args = argp.parse_args()

    original_tree = build_npm_tree(args.baseline_path)
    tainted_tree = build_npm_tree(args.tainted_path)

    diffs = deepdiff.DeepDiff(original_tree, tainted_tree)
    pprint(diffs, indent=2)


if __name__ == '__main__':
    main()
