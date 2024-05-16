require 'benchmark'

dev = ARGV[0]

def perf(cmd, n)
    sum = 0
    n.times do
        time = Benchmark.realtime do
            system(cmd, :err => File::NULL)
        end
        sum += time
    end
    sum / n
end

for bs in [4, 16, 64, 256, 1024] do
    amount = bs * 1000
    time = perf("dd if=#{dev} of=/dev/null bs=#{bs}k count=1000 iflag=direct", 10)
    p amount/time
end
