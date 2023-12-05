#!/bin/bash

src_folder="/storage/emulated/0/shared/exo"
dest_folder="/storage/emulated/0/Download/organized_files"
files_per_folder=50
total_folders=20

# Create the destination folder
mkdir -p "$dest_folder"

for ((i = 1; i <= total_folders; i++)); do
  mkdir -p "$dest_folder/folder_$i"
done

count=0
folder_count=1

for file in "$src_folder"/*; do
  if [ "$count" -eq "$files_per_folder" ]; then
    count=0
    folder_count=$((folder_count + 1))
  fi

  mv "$file" "$dest_folder/folder_$folder_count"
  count=$((count + 1))
done
