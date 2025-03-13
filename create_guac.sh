#!/bin/bash

PROJECT="guac"

# Get the current date in YYYYMMDD format
current_date=$(date +%Y%m%d)


# Create the PROJECT_<date>.tar.gz archive with the current date in the filename
archive_name="${PROJECT}_${current_date}.tar.gz"
tar czf "$archive_name" --transform 's,^,guac/,' run.sh utils/* || {
  echo "Failed to create tar archive"
  rm -r "$temp_dir"
  exit 1
}

# Clean up the temporary directory
rm -r "${temp_dir}"
ln -sf ${archive_name} "${PROJECT}_latest.tar.gz"
echo "Archive of ${PROJECT} created successfully: $archive_name"

