python run_attacks.py --delay 375 
echo "Generating plots..."
python plot.py --save --attack div --output ./plots
python plot.py --save --attack dup --output ./plots
python plot.py --save --attack opt --output ./plots
echo "Done! Please check ./plots for all generated plots."
