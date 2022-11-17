var product = [
  {
	id: 1,
    img: '/images/produtos/01.png',
    name: 'Grooming para Cabelo B.URB Midlands 250ml',
    preco: 59.00,
    estoque: 100
  },
  {
	 id: 2,
     img: '/images/produtos/02.png',
     name: 'Shampoo Barba Forte Gasoline 250 ml',
     preco: 30.00,
     estoque: 100
  },
  {
	 id: 3,
     img: '/images/produtos/03.png',
     name: 'Kit de Barbear Go. Clinical',
     preco: 59.00,
     estoque: 100
  },
  {
	id: 4,
    img: '/images/produtos/04.png',
    name: 'Shampoo Sólido Nutrição da Kae Cosmeticos - 75g',
    preco: 50.00,
    estoque: 100
  },
  {
	id: 5,
    img: '/images/produtos/05.png',
    name: 'Protetor Solar episol Color Tom 6 Negro 70 FPS 40g',
    preco: 69.00,
    estoque: 100
  },
  {
	id: 6,
    img: '/images/produtos/06.png',
    name: 'Truss Uso Obrigatório - Tratamento Reconstrutor 260ml',
    preco: 90.00,
    estoque: 100
  },
  {
	id: 7,
    img: '/images/produtos/07.png',
    name: 'Condicionador Para Cabelo Don Alcides Rolling Stones - 300g',
    preco:  70.00,
    estoque: 100
  },  
  {
	id: 8,
    img:'/images/produtos/08.png',
    name: 'Pomada em Pó Route 66',
    preco: 20.00,
    estoque: 100
  },
  
]
const dadosProduct = JSON.stringify(product)//JSON
const products = JSON.parse(dadosProduct)//JS
localStorage.setItem('product',JSON.stringify(product)) 
JSON.parse(localStorage.getItem('product'));

function createCard(){
	product.map((i)=>{
		const divcard = document.querySelector(".produto")
		const card = document.createElement("div")
		const title = document.createElement("h1")
		const preco = document.createElement("p")
		const button = document.createElement("button")
		const img = document.createElement("img");
		

		card.classList.add("produto1")
		button.classList.add("btnAddCarrinho")
		img.classList.add("img-produtos")
		
		img.src = i.img
		title.innerHTML = i.name
		preco.innerHTML = "R$ " + i.preco
		
		
		
		button.innerHTML = `<p class="btnAddCarrinho" onclick="addCarrinho(${i.id})">Carrinho</p>`
		
		card.appendChild(img)
		card.appendChild(title)
		card.appendChild(preco)
		card.appendChild(button)
		divcard.appendChild(card)
	})
}

createCard();

var cart=[]

function addCarrinho(id) {
	event.preventDefault()
	//alerta de produto existente some= algum em array
  if(cart.some((itens) => itens.id === id)){
		quantidade('plus',id)
	}else{
	 const item = product.find((products) => products.id === id)
  	 cart.push({
		...item,//destrui o objeto
      	numberOfUnits: 1,
	 })
	}
	updateCart();
}


function updateCart(){
	creaCart();
    renderSubtotal();
}

function creaCart(){
	const card_cart =document.querySelector(".card_cart")
		card_cart.innerHTML='';
		cart.forEach((item) => {
	    card_cart.innerHTML += `
	    	<div class="produto_carrinho">
	               <img class= "img-produtos" src="${item.img}" alt="${item.name}"/>
	               <p class="title_carrinho"> ${item.name}</p>	
	               <p class="preco_carrinho"><small>R$</small>${item.preco}</p>
	     
	               <div class="units">
                		<div class="btn minus" onclick="quantidade('minus', ${item.id})">-</div>
                		<div class="number">${item.numberOfUnits}</div>
                		<div class="btn plus" onclick="quantidade('plus', ${item.id})">+</div> 
                	</div>
                 <div class="remove" onclick="removerItemCart(${item.id})">
                 		<img src='/images/lixo.png'/>
                		<p>Remover <p> 
                	</div>                     
	        </div>`;
	  });
	  renderSubtotal()
}

const contagem=document.querySelector('.total-item')
const total = document.querySelector(".total")
function renderSubtotal(){
	let totalPreco = 0, totalItem = 0;
	
	cart.forEach((item) => {
		totalPreco += parseFloat(item.preco)*item.numberOfUnits
		totalItem += item.numberOfUnits
	})

   total.innerHTML = `
   			 <a class="closes" onclick="closes()">X</a>
              <img class="teste" src="/images/logo_sem_fundo.png" />
              <div class="text_total">
	              <p>Valor Total: R$ ${totalPreco.toFixed(2)}</p>
	               <p>Total Item: ${totalItem}</p>
	           </div>
	                              
	   `;
	   
	contagem.innerHTML = totalItem
	

}


const modal = document.querySelector(".cart_principal")
const openModal = document.querySelector(".carrinho")
const close = document.querySelector(".closes")

	  openModal.addEventListener('click', () => {
		modal.style.display="flex"
 		 modal.showModal();
	  });
function closes(){
	modal.style.display="none"
		modal.close()
	}	
 		


	


function quantidade(action, id) {
	cart = cart.map((item) => {
		var numberOfUnits = item.numberOfUnits;
		
		if(item.id === id){
			if(action === 'minus' && numberOfUnits > 1){
				numberOfUnits--
			}else if(action === 'plus' && numberOfUnits < item.estoque){
				numberOfUnits++
			}
		}
		return{
			...item,
			numberOfUnits,
		}
	});
	updateCart()
 }

function removerItemCart(id){
	cart = cart.filter((item)=> item.id !==id)
	
	updateCart()
}

creaCart()
addCarrinho();
