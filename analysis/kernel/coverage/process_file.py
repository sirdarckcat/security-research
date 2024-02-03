#!/usr/bin/python3

import csv
import html
import re
import sys
import urllib.request

def get_paths(haystack):
    groups = re.findall(r"<a .* id=\"(.*?)\" onclick=\"onFileClick\(\s*(.*?)\s*\)\">", haystack)
    return [(m[1], m[0]) for m in groups]


def get_syzkaller_programs(haystack):
    programs = []
    pos = -1 
    while True:
        prog_section = '<pre class="file" id="prog_'
        pos = haystack.find(prog_section, pos + 1)
        if pos == -1:
            break
        index_pos = pos + len(prog_section)
        pos = haystack.find('"', index_pos + 1)
        if pos == -1:
            break
        index = haystack[index_pos:pos]
        program_pos = pos + len('">')
        pos=haystack.find("</pre>", program_pos)
        program=html.unescape(haystack[program_pos:pos].strip())
        programs.append((index, program))
    return programs


def get_file_line_prog(haystack):
    pos = -1 
    covered_files = []
    while True:
        file_section = 'class="file" id="contents_'
        pos = haystack.find(file_section, pos + 1)
        if pos == -1:
            break
        file_index_pos = pos + len(file_section)
        pos = haystack.find('"', file_index_pos + 1)
        if pos == -1:
            break
        index = haystack[file_index_pos:pos]
        prefix_pos = pos + len('"')
        prefix = "><table><tr><td class='count'>"
        coverage_pos = pos + len('"') + len(prefix)
        if haystack[prefix_pos:coverage_pos]!=prefix:
            # error
            continue
        pos=haystack.find("</td>", coverage_pos)
        coverage=haystack[coverage_pos:pos].splitlines()
        covered_lines = []
        for line_idx, line in enumerate(coverage):
            line_idx += 1 # 0-indexed
            program_event = "onProgClick("
            if program_event in line:
                comma_pos = line.find(",", len(program_event))
                prog_id = line[line.find(program_event)+len(program_event):comma_pos]
                covered_lines.append((line_idx, prog_id))
        covered_files.append((index, covered_lines))
    return covered_files

def get_coverage_info(haystack):
    coverage_info = []
    paths = dict(get_paths(haystack))
    progs = dict(get_syzkaller_programs(haystack))
    coverage = get_file_line_prog(haystack)
    for covered_file_index, covered_lines in coverage:
        for line_no, prog_id in covered_lines:
            coverage_info.append((
                paths[covered_file_index],
                line_no,
                progs[prog_id]
            ))
    return coverage_info

def main():
    csv_out = csv.writer(sys.stdout)
    csv_in = csv.reader(sys.stdin)
    for row in csv_in:
        for line in get_coverage_info(urllib.request.urlopen(row[0]).read().decode('utf-8')):
            csv_out.writerow(line)


if __name__ == '__main__':
    sys.exit(main())
