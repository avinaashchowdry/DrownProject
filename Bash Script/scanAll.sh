parallel=6
max_bg=30
absolute_max_bg=80
max_load_avg=50

if [ $(ulimit -u) -lt $((10*absolute_max_bg)) ]; then
  echo "Max user process too low"
  exit 1
fi

function wait_for_jobs() {
  local numJobs
  numJobs=$(jobs | wc -l)

  while [ $numJobs -gt $1 ] || awk -v maxload=$max_load_avg '{ if  ($1 < maxload) exit 1 }' /proc/loadavg;
  do
    if awk -v maxload=$max_load_avg '{ if ($1 < maxload) exit 1 }' /proc/loadavg && [ $numJobs -lt $absolute_max_bg ]; then
      return
    fi
    sleep 1
    numJobs=$(jobs | wc -l)
  done
}

function scan_hosts() {
  echo "`sh ./scanHost.sh -s $2 -r $1`"
}

i=0
count=$(wc -l new.csv | awk '{print $1}')

while [ $i -lt $count ]
do
  #echo "Processing $i to $((i + parallel))"
 
  for t in $(tail -$(($count - $i)) new.csv | head -$parallel)
  do
    rank=`echo $t | cut -d ',' -f 1`
    target=`echo $t | cut -d ',' -f 2 |cut -d "/" -f 1`
    #echo "$rank $target"
    (scan_hosts $rank $target)&
  done
  
  sleep 3
  i=$((i + parallel))
  wait_for_jobs $max_bg
done
