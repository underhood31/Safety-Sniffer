import curses
import time
import sniffer
import threading

snif=sniffer.sniffer()

def getSet(n):
    if(n%2==1):
        return list(snif.save.allURLs)
    else:
        return list(snif.save.badURLs)
def main(window):
    curses.curs_set(0)
    h,w=window.getmaxyx()
    curses.init_pair(2, curses.COLOR_WHITE,curses.COLOR_BLACK)
    curses.init_pair(1, curses.COLOR_BLACK,curses.COLOR_WHITE)

    string="Safety Sniffer"
    window.addstr(0,w//2-len(string)//2,string)
    col=1
    while True:
        window.clear()
        window.attron(curses.color_pair(col%2))
        str2="All Websites Visited"
        window.addstr(1,w//4-len(str2)//2,str2)
        window.attroff(curses.color_pair(col%2))
        window.attron(curses.color_pair((col+1)%2))
        str3="Unsafe Websites Visited"
        window.addstr(1,(3*w)//4-len(str3)//2,str3)
        window.attroff(curses.color_pair((col+1)%2))

        #printing the list
        lst=getSet(col)
        for i in range(len(lst)):
            window.addstr((4+i),w//2-len(lst[i])//2,lst[i])
        window.refresh()
        inp=window.getch()
        if(inp==curses.KEY_LEFT or inp==curses.KEY_RIGHT):
        
            col+=1
        elif inp == 113 or  inp==27:
            break
        
if __name__ == "__main__":
    t2 = threading.Thread(target=snif.start_sniffing, args=()) 
    t2.start()
    curses.wrapper(main)
    # t1 = threading.Thread(target=curses.wrapper, args=(main)) 

    # t1.start()

    # t1.join()
    t2.raise_exception()