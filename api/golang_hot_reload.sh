#!/usr/bin/env bash

SCRIBE_SERVER="/go/src/exec_dir/Scribe"
WORKDIR="/go/src/api"

log() {
  echo "STARTSCRIPT: $1"
}

buildServer() {
  log "Building server binary"
  go build -gcflags "all=-N -l" -o $SCRIBE_SERVER cmd/scribe/main.go
  if [ $? -eq 0 ]; then
      echo "Server binary build OK."
  else
      echo "Server binary build FAILED."
      exit 0
  fi
  chmod +x $SCRIBE_SERVER
}

runTests() {
  log "Run tests"
  go test -v ./...
}

runServer() {
  log "Run server"
  log "Killing old server"
  killall dlv
  killall Scribe
  log "Run in debug mode"
  /go/bin/dlv --listen=:40000 --headless=true --api-version=2 --accept-multiclient exec $SCRIBE_SERVER &
}

rerunServer() {
  log "Rerun server"
  buildServer
  runServer
  runTests
}

liveReloading() {
  log "Run liveReloading"
  inotifywait -e "MODIFY,DELETE,MOVED_TO,MOVED_FROM" -m -r --include '.go$' $WORKDIR | (
    # read changes from inotify, batch results to a second (read -t 1)
    while true; do
      read path action file
      ext=${file: -3}
      if [[ "$ext" == ".go" ]]; then
        echo "$file"
      fi
    done
  ) | (
    WAITING=""
    while true; do
      file=""
      read -t 1 file
      if test -z "$file"; then
        if test ! -z "$WAITING"; then
          echo "CHANGED"
          WAITING=""
        fi
      else
        log "File ${file} changed" >>/tmp/filechanges.log
        WAITING=1
      fi
    done
  ) | (
    # read statement release when some file has been changed
    while true; do
      read TMP
      log "File Changed. Reloading..."
      rerunServer
    done
  )
}

initializeFileChangeLogger() {
  echo "" > /tmp/filechanges.log
  tail -f /tmp/filechanges.log &
}

main() {
  runTests
  initializeFileChangeLogger
  buildServer
  runServer
  liveReloading
}

main