#include<stdio.h>
#include<stdlib.h>
#include<malloc.h>
#include<string.h>
#include<signal.h>
#include<stdbool.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<pthread.h>
#include<linux/if_packet.h>
#include<netinet/in.h>		 
#include<netinet/if_ether.h>    // 이더넷 파일을 위한 헤더 파일
#include<netinet/ip.h>		// 아이피 헤더를 위한 헤더 파일
#include<netinet/udp.h>		// udp 헤더를 위한 헤더 파일
#include<netinet/tcp.h>
#include<netdb.h>
#include<arpa/inet.h>           // to avoid warning at inet_ntoa



FILE* log_txt;
int total,tcp,udp,icmp,igmp,other,iphdrlen;

struct sockaddr saddr;
struct sockaddr_in source,dest;
void ethernet_header(unsigned char* buffer,int buflen); // 이더넷 헤더를 위한 함수
void ip_header(unsigned char* buffer,int buflen); // IP 헤더를 위한 함수
void payload(unsigned char* buffer,int buflen) ; //paload에 대한 함수
void tcp_header(unsigned char* buffer,int buflen) ; // TCP PROTOCOL을 이용하는 패킷을 위한 함수
void udp_header(unsigned char* buffer, int buflen); // UDP PROTOCOL을 이용하는 패킷을 위한 함수
void data_process(unsigned char* buffer,int buflen); // 받은 패킷 중에 TCP 또는 UDP일 때 다르게 캡처하기 위한 함수
void menu(); // 메뉴 선택 함수
void *PacketCapture();
int dnscapture();  //dns 

pthread_t tid;        // thread id
bool check = false;


int main(int argc, char*argv[])
{
    int rc;
    char stop;
    char ch;
    int num;
	pthread_t thread; // 쓰레드
    

    
    while(1){
        if(check == false){
            menu(); // 메뉴 보여준다.
            printf("메뉴 번호 입력:");
	    scanf("%d",&num);
	    __fpurge(stdin);
        }

        if(num == 1 && check == false){
            check = true;
            rc = pthread_create(&thread, NULL, PacketCapture, NULL);
            if(rc<0){
                printf("ERROR, return code from pthread_create() is %d\n", rc);
                exit(-1);
            }
        }else if(num == 2){
            printf("프로그램을 종료합니다.\n");
            return 0;
        }else if(num != 1 && num !=2){
		printf("check the number plz\n");
		continue;
	}

	if(rc==0){
	       while(1){	
        		printf("Capturing~~ (q: stop) >>>>");
			scanf("%c",&stop);
			__fpurge(stdin);
			if(stop == 'q' && check==true){
           			 // Thread에게 Signal을 보냄 
            			printf("capture stop\n");
            			pthread_cancel(tid);
            			check = false;
				break;
			}else{
				printf("plz write correctly!\n");
				continue;
			}
	       }
		
	 }
    }
   
    
	pthread_exit(NULL);

}

int dnscapture(){
	 int i;
        struct hostent *he;
        struct in_addr **addr_list;

        char *domain = malloc(sizeof(char)*20);

        printf("domain plz >> ");
        scanf("%s",domain);

        he = gethostbyname(domain);

        printf("Name : %s\n", he->h_name);
        printf("IP addresses: \n");
        addr_list = (struct in_addr **)he->h_addr_list;

        for(i=0;addr_list[i] != NULL; i++)
        {
                printf("%s \n",inet_ntoa(*addr_list[i]));
        };
        printf("\n");

        return 0;
}


void ethernet_header(unsigned char* buffer,int buflen) 
{
	struct ethhdr *eth = (struct ethhdr *)(buffer);
	fprintf(log_txt,"\nEthernet Header\n");
	fprintf(log_txt,"\t|-Source Address	: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
	fprintf(log_txt,"\t|-Destination Address	: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
	fprintf(log_txt,"\t|-Protocol		: %d\n",eth->h_proto);

}



void ip_header(unsigned char* buffer,int buflen)
{
	struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));

	iphdrlen =ip->ihl*4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ip->saddr;     
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = ip->daddr;     

	fprintf(log_txt , "\nIP Header\n");

	fprintf(log_txt , "\t|-Version              : %d\n",(unsigned int)ip->version);
	fprintf(log_txt , "\t|-Internet Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)ip->ihl,((unsigned int)(ip->ihl))*4);
	fprintf(log_txt , "\t|-Type Of Service   : %d\n",(unsigned int)ip->tos);
	fprintf(log_txt , "\t|-Total Length      : %d  Bytes\n",ntohs(ip->tot_len));
	fprintf(log_txt , "\t|-Identification    : %d\n",ntohs(ip->id));
	fprintf(log_txt , "\t|-Time To Live	    : %d\n",(unsigned int)ip->ttl);
	fprintf(log_txt , "\t|-Protocol 	    : %d\n",(unsigned int)ip->protocol);
	fprintf(log_txt , "\t|-Header Checksum   : %d\n",ntohs(ip->check));
	fprintf(log_txt , "\t|-Source IP         : %s\n", inet_ntoa(source.sin_addr));
	fprintf(log_txt , "\t|-Destination IP    : %s\n",inet_ntoa(dest.sin_addr));
}

void payload(unsigned char* buffer,int buflen) 
{
	int i=0;
	unsigned char * data = (buffer + iphdrlen  + sizeof(struct ethhdr) + sizeof(struct udphdr));
	fprintf(log_txt,"\nData\n");
	int remaining_data = buflen - (iphdrlen  + sizeof(struct ethhdr) + sizeof(struct udphdr));
	for(i=0;i<remaining_data;i++)
	{
		if(i!=0 && i%16==0)
			fprintf(log_txt,"\n");
		fprintf(log_txt," %.2X ",data[i]);
	}

	fprintf(log_txt,"\n");



}

void tcp_header(unsigned char* buffer,int buflen)
{
	fprintf(log_txt,"\n*************************TCP Packet******************************");
   	ethernet_header(buffer,buflen);
  	ip_header(buffer,buflen);

   	struct tcphdr *tcp = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
   	fprintf(log_txt , "\nTCP Header\n");
   	fprintf(log_txt , "\t|-Source Port          : %u\n",ntohs(tcp->source));
   	fprintf(log_txt , "\t|-Destination Port     : %u\n",ntohs(tcp->dest));
   	fprintf(log_txt , "\t|-Sequence Number      : %u\n",ntohl(tcp->seq));
   	fprintf(log_txt , "\t|-Acknowledge Number   : %u\n",ntohl(tcp->ack_seq));
   	fprintf(log_txt , "\t|-Header Length        : %d DWORDS or %d BYTES\n" ,(unsigned int)tcp->doff,(unsigned int)tcp->doff*4);
	fprintf(log_txt , "\t|----------Flags-----------\n");
	fprintf(log_txt , "\t\t|-Urgent Flag          : %d\n",(unsigned int)tcp->urg);
	fprintf(log_txt , "\t\t|-Acknowledgement Flag : %d\n",(unsigned int)tcp->ack);
	fprintf(log_txt , "\t\t|-Push Flag            : %d\n",(unsigned int)tcp->psh);
	fprintf(log_txt , "\t\t|-Reset Flag           : %d\n",(unsigned int)tcp->rst);
	fprintf(log_txt , "\t\t|-Synchronise Flag     : %d\n",(unsigned int)tcp->syn);
	fprintf(log_txt , "\t\t|-Finish Flag          : %d\n",(unsigned int)tcp->fin);
	fprintf(log_txt , "\t|-Window size          : %d\n",ntohs(tcp->window));
	fprintf(log_txt , "\t|-Checksum             : %d\n",ntohs(tcp->check));
	fprintf(log_txt , "\t|-Urgent Pointer       : %d\n",tcp->urg_ptr);

	payload(buffer,buflen);

fprintf(log_txt,"*****************************************************************\n\n\n");
}

void udp_header(unsigned char* buffer, int buflen)
{
	fprintf(log_txt,"\n*************************UDP Packet******************************");
	ethernet_header(buffer,buflen);
	ip_header(buffer,buflen);
	fprintf(log_txt,"\nUDP Header\n");

	struct udphdr *udp = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
	fprintf(log_txt , "\t|-Source Port    	: %d\n" , ntohs(udp->source));
	fprintf(log_txt , "\t|-Destination Port	: %d\n" , ntohs(udp->dest));
	fprintf(log_txt , "\t|-UDP Length      	: %d\n" , ntohs(udp->len));
	fprintf(log_txt , "\t|-UDP Checksum   	: %d\n" , ntohs(udp->check));

	payload(buffer,buflen);

	fprintf(log_txt,"*****************************************************************\n\n\n");



}

void data_process(unsigned char* buffer,int buflen)
{
	struct iphdr *ip = (struct iphdr*)(buffer + sizeof (struct ethhdr));
	++total;
	/* we will se UDP Protocol only*/ 
	switch (ip->protocol)    //see /etc/protocols file 
	{

		case 6:
			++tcp;
			tcp_header(buffer,buflen);
			break;

		case 17:
			++udp;
			udp_header(buffer,buflen);
			break;

		default:
			++other;

	}
	printf("TCP: %d  UDP: %d  Other: %d  Toatl: %d  \r",tcp,udp,other,total);


}

void menu(){
	system("clear");
    printf("--------------------------------------------------\n");
	printf("컴퓨터 네트워크 1 조\n");
    printf("1. 패킷 캡처 start\n2. 프로그램 종료\n");
    printf("--------------------------------------------------\n");
}

void* PacketCapture(){
    int sock_r,saddr_len,buflen;
    unsigned char* buffer = (unsigned char *)malloc(65536); // 동적으로 버퍼 할당
    memset(buffer,0,65536);
    
    tid = pthread_self();
	log_txt=fopen("log.txt","w");
	if(!log_txt) // 파일이 열리지 않았을 때
	{
		printf("log.txt 파일을 열 수 없습니다.\n");
		exit(-1);

	}

    sock_r=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL)); 
	if(sock_r<0) // 소켓이 열리지 않았을 때
	{
		printf("소켓 에러\n");
		exit(-1);
	}

    while(1){
        saddr_len=sizeof(saddr);
		buflen=recvfrom(sock_r,buffer,65536,0,&saddr,(socklen_t *)&saddr_len);

        if(buflen<0) // 버퍼를 받지 못했을 때
	 	{
		    printf("recvfrom에서부터 데이터를 받지 못했음\n");
		    exit(-1);
		}

		    fflush(log_txt);
	        data_process(buffer,buflen);
 
    }
    close(sock_r);// use signals to close socket 
    pthread_exit(NULL);
}
